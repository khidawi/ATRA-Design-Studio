"""
A two-layer GraphSAGE, trained self-supervised on normal snapshots (ASTRA phase 11, step 11b), in plain PyTorch.

    encoder    h1 = relu(W1 [x ; mean of the neighbours' x]),  h2 = W2 [h1 ; mean of the neighbours' h1]      (mean aggregation, two hops)
    decoders   from h2 it reconstructs the node's own features and the mean of its neighbours' features, and predicts links (the dot product of two embeddings)
    training   minimise reconstruction error and a link-prediction loss on snapshots of normal traffic only; negative links are random pairs that are not edges
    score      the reconstruction error of an agent node; normalised against the agent's own normal spread by the median and the median absolute deviation (robust: one odd window does not
               move it), so it is a number of robust standard deviations above that agent's usual

The embedding is narrower than the features, so a node whose pattern is unlike the patterns it learned to compress reconstructs badly. There is no per-node identity anywhere: a node is
described by what it does and what is around it.
"""
import math
import random
from typing import Dict, List, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

from . import graph as G


def seed_everything(seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)
    torch.set_num_threads(1)


def neighbour_mean(x: torch.Tensor, edges: torch.Tensor) -> torch.Tensor:
    """Mean of the neighbours' rows for every node; a node with no neighbour gets zeros. Edges are listed once and used in both directions."""
    n = x.shape[0]
    if edges.numel() == 0:
        return torch.zeros_like(x)
    src = torch.cat([edges[:, 0], edges[:, 1]])
    dst = torch.cat([edges[:, 1], edges[:, 0]])
    agg = torch.zeros_like(x).index_add(0, dst, x[src])
    deg = torch.zeros(n, 1).index_add(0, dst, torch.ones(len(dst), 1)).clamp(min=1)
    return agg / deg


class SAGE(nn.Module):
    def __init__(self, dim: int, hidden: int = 24, emb: int = 6):
        super().__init__()
        self.dim, self.hidden, self.emb = dim, hidden, emb
        self.w1 = nn.Linear(2 * dim, hidden)
        self.w2 = nn.Linear(2 * hidden, emb)
        self.dec_self = nn.Linear(emb, dim)
        self.dec_nbr = nn.Linear(emb, dim)

    def encode(self, x: torch.Tensor, edges: torch.Tensor) -> torch.Tensor:
        h1 = torch.relu(self.w1(torch.cat([x, neighbour_mean(x, edges)], dim=-1)))
        return self.w2(torch.cat([h1, neighbour_mean(h1, edges)], dim=-1))

    def node_error(self, x: torch.Tensor, edges: torch.Tensor) -> Tuple[torch.Tensor, torch.Tensor]:
        z = self.encode(x, edges)
        e_self = ((self.dec_self(z) - x) ** 2).mean(-1)
        e_nbr = ((self.dec_nbr(z) - neighbour_mean(x, edges)) ** 2).mean(-1)
        return e_self + e_nbr, z

    def loss(self, x: torch.Tensor, edges: torch.Tensor, rng: random.Random) -> torch.Tensor:
        err, z = self.node_error(x, edges)
        rec = err.mean()
        if edges.numel() == 0:
            return rec
        pos = (z[edges[:, 0]] * z[edges[:, 1]]).sum(-1)
        n = x.shape[0]
        have = {(int(a), int(b)) for a, b in edges.tolist()} | {(int(b), int(a)) for a, b in edges.tolist()}
        neg_pairs = []
        for _ in range(len(edges) * 2):
            a, b = rng.randrange(n), rng.randrange(n)
            if a != b and (a, b) not in have:
                neg_pairs.append((a, b))
        if not neg_pairs:
            return rec
        ng = torch.tensor(neg_pairs)
        neg = (z[ng[:, 0]] * z[ng[:, 1]]).sum(-1)
        link = F.binary_cross_entropy_with_logits(pos, torch.ones_like(pos)) + F.binary_cross_entropy_with_logits(neg, torch.zeros_like(neg))
        return rec + 0.1 * link


def tensors(s: G.Snapshot) -> Tuple[torch.Tensor, torch.Tensor]:
    return torch.tensor(s.x, dtype=torch.float), (torch.tensor(s.edges, dtype=torch.long) if s.edges else torch.zeros(0, 2, dtype=torch.long))


def train(snaps: List[G.Snapshot], dim: int, seed: int = 1, epochs: int = 60, lr: float = 5e-3, hidden: int = 24, emb: int = 6) -> Tuple[SAGE, List[float]]:
    """Train on snapshots of normal traffic only. Returns the model and the mean loss per epoch."""
    seed_everything(seed)
    model = SAGE(dim, hidden, emb)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    rng = random.Random(seed)
    data = [tensors(s) for s in snaps]
    curve: List[float] = []
    for _ in range(epochs):
        order = list(range(len(data)))
        rng.shuffle(order)
        total = 0.0
        for i in order:
            x, e = data[i]
            loss = model.loss(x, e, rng)
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total += loss.item()
        curve.append(total / len(order))
    return model, curve


@torch.no_grad()
def agent_errors(model: SAGE, snap: G.Snapshot) -> Dict[str, float]:
    """The reconstruction error of every agent node of a snapshot."""
    model.eval()
    x, e = tensors(snap)
    err, _ = model.node_error(x, e)
    return {name: float(err[i]) for name, i in snap.agent_nodes()}


def robust_norm(values: List[float]) -> List[float]:
    """[median, scaled median absolute deviation] of an agent's errors on its own normal windows, with a floor so a very steady node does not turn tiny noise into a huge score."""
    s = sorted(values)
    med = s[len(s) // 2] if len(s) % 2 else 0.5 * (s[len(s) // 2 - 1] + s[len(s) // 2])
    dev = sorted(abs(v - med) for v in values)
    mad = dev[len(dev) // 2] if len(dev) % 2 else 0.5 * (dev[len(dev) // 2 - 1] + dev[len(dev) // 2])
    return [round(med, 8), round(max(1.4826 * mad, 0.05 * max(med, 1e-6), 1e-4), 8)]


def state_dict_checksum(model: SAGE) -> str:
    import hashlib
    h = hashlib.sha256()
    for k, v in sorted(model.state_dict().items()):
        h.update(k.encode())
        h.update(",".join(f"{x:.7e}" for x in v.detach().flatten().tolist()).encode())
    return h.hexdigest()

"""
The temporal graph network (ASTRA phase 10, step 10b), in plain PyTorch.

It reads a stream of events (agent, kind, target, time) in time order and, before seeing each event, predicts it. How surprised it is, the negative log-likelihood of what actually happened,
is the score. It is trained on normal traffic only (self-supervised: the next event is the label), so it needs no examples of attacks.

    memory          one vector per node (an agent, a tool, a data store), kept in a GRU and updated by every event the node takes part in
    message         for an event, a small network over (memory of the source, memory of the target, kind, time since the node's last event) for each of the two nodes
    embedding       a temporal attention over the node's last few interactions (their memory, their kind, how long ago): this is how order and timing enter
    decoder         from the source node's embedding it predicts three things: the target, the kind and the gap (log-scale bucket) until the node's next event

Events of a batch are predicted from the memory as it was before the batch, then the memory is updated with all of them (the standard way to make a TGN trainable in batches). Everything is
seeded and run on CPU with deterministic algorithms, so the same data and seed give the same weights.
"""
import math
import random
from typing import Any, Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

N_BINS = 8
UNK = "<unk>"


def seed_everything(seed: int) -> None:
    random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True)
    torch.set_num_threads(1)


def gap_bin(dt: float) -> int:
    """Log-scale bucket of a gap in seconds: <1s, 1-2, 2-4, 4-8, 8-16, 16-32, 32-64, longer."""
    return 0 if dt < 1 else min(N_BINS - 1, int(math.log2(dt)) + 1)


class Vocab:
    def __init__(self, nodes: List[str], kinds: List[str]):
        self.nodes, self.kinds = [UNK] + sorted(set(nodes) - {UNK}), [UNK] + sorted(set(kinds) - {UNK})
        self.node_id = {n: i for i, n in enumerate(self.nodes)}
        self.kind_id = {k: i for i, k in enumerate(self.kinds)}

    @classmethod
    def of(cls, events: List[Dict[str, Any]]) -> "Vocab":
        return cls([e["agent"] for e in events] + [e["target"] for e in events], [e["kind"] for e in events])

    def node(self, n: str) -> int:
        return self.node_id.get(n, 0)

    def kind(self, k: str) -> int:
        return self.kind_id.get(k, 0)

    def dump(self) -> Dict[str, List[str]]:
        return {"nodes": self.nodes[1:], "kinds": self.kinds[1:]}


class TimeEnc(nn.Module):
    def __init__(self, d: int):
        super().__init__()
        self.w = nn.Parameter(torch.linspace(0.2, 2.5, d))
        self.b = nn.Parameter(torch.zeros(d))

    def forward(self, dt: torch.Tensor) -> torch.Tensor:
        return torch.cos(torch.log1p(dt.clamp(min=0)).unsqueeze(-1) * self.w + self.b)


class State:
    """Memory and recent-neighbour buffers of every node. Not a parameter: it is rebuilt by replaying events."""

    def __init__(self, n: int, d: int, m: int):
        self.mem = torch.zeros(n, d)
        self.last_t = torch.full((n,), float("-inf"))
        self.nb_id = torch.full((n, m), -1, dtype=torch.long)
        self.nb_kind = torch.zeros(n, m, dtype=torch.long)
        self.nb_t = torch.zeros(n, m)
        self.ptr = torch.zeros(n, dtype=torch.long)
        self.m = m

    def detach(self) -> None:
        self.mem = self.mem.detach()

    def push(self, node: int, other: int, kind: int, t: float) -> None:
        p = int(self.ptr[node]) % self.m
        self.nb_id[node, p], self.nb_kind[node, p], self.nb_t[node, p] = other, kind, t
        self.ptr[node] += 1


class TGN(nn.Module):
    def __init__(self, n_nodes: int, n_kinds: int, d: int = 32, m: int = 8, d_k: int = 8, d_t: int = 8):
        super().__init__()
        self.n_nodes, self.n_kinds, self.d, self.m = n_nodes, n_kinds, d, m
        self.node_emb = nn.Embedding(n_nodes, d)
        self.kind_emb = nn.Embedding(n_kinds, d_k)
        self.te = TimeEnc(d_t)
        self.msg = nn.Sequential(nn.Linear(2 * d + d_k + d_t, d), nn.ReLU())
        self.gru = nn.GRUCell(d, d)
        self.q = nn.Linear(d, d)
        self.k = nn.Linear(d + d_k + d_t, d)
        self.v = nn.Linear(d + d_k + d_t, d)
        self.out = nn.Linear(2 * d, d)
        self.h_target = nn.Linear(d, n_nodes)
        self.h_kind = nn.Linear(d, n_kinds)
        self.h_gap = nn.Linear(d, N_BINS)

    def embed(self, S: State, src: torch.Tensor, t: torch.Tensor) -> torch.Tensor:
        base = S.mem[src] + self.node_emb(src)
        ids = S.nb_id[src]                                                       # (B, m)
        mask = ids >= 0
        nbr = torch.cat([S.mem[ids.clamp(min=0)], self.kind_emb(S.nb_kind[src]), self.te(t.unsqueeze(1) - S.nb_t[src])], dim=-1)
        att = (self.k(nbr) * self.q(base).unsqueeze(1)).sum(-1) / math.sqrt(self.d)
        att = att.masked_fill(~mask, -1e9)
        w = torch.softmax(att, dim=1) * mask.float()                             # a node with no neighbours attends to nothing
        ctx = (w.unsqueeze(-1) * self.v(nbr)).sum(1)
        return torch.relu(self.out(torch.cat([base, ctx], dim=-1)))

    def predict(self, S: State, src: torch.Tensor, dst: torch.Tensor, kind: torch.Tensor, t: torch.Tensor) -> torch.Tensor:
        """The surprise of each event of the batch: NLL of its target, its kind and the gap since its source's previous event, all predicted from the history before the batch."""
        h = self.embed(S, src, t)
        prev = S.last_t[src]
        gap = torch.where(torch.isinf(prev), torch.zeros_like(t), t - prev)
        gbin = torch.tensor([gap_bin(float(x)) for x in gap], dtype=torch.long)
        return F.cross_entropy(self.h_target(h), dst, reduction="none") + F.cross_entropy(self.h_kind(h), kind, reduction="none") + F.cross_entropy(self.h_gap(h), gbin, reduction="none")

    def update(self, S: State, src: torch.Tensor, dst: torch.Tensor, kind: torch.Tensor, t: torch.Tensor) -> None:
        """Take a batch of events into the memory: a message to each of the two nodes of every event, averaged per node, through the GRU."""
        new_mem = S.mem.clone()
        agg = torch.zeros(self.n_nodes, self.d)
        cnt = torch.zeros(self.n_nodes, 1)
        for a, b in ((src, dst), (dst, src)):
            prev = S.last_t[a]
            gap = torch.where(torch.isinf(prev), torch.zeros_like(t), t - prev)
            m = self.msg(torch.cat([S.mem[a], S.mem[b], self.kind_emb(kind), self.te(gap)], dim=-1))
            agg = agg.index_add(0, a, m)
            cnt = cnt.index_add(0, a, torch.ones(len(a), 1))
        touched = torch.nonzero(cnt.squeeze(-1) > 0).squeeze(-1)
        new_mem[touched] = self.gru(agg[touched] / cnt[touched], S.mem[touched])
        S.mem = new_mem
        for s_, d_, k_, t_ in zip(src.tolist(), dst.tolist(), kind.tolist(), t.tolist()):
            S.push(s_, d_, k_, t_)
            S.push(d_, s_, k_, t_)
            S.last_t[s_], S.last_t[d_] = t_, t_


def tensors(events: List[Dict[str, Any]], vocab: Vocab) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor, torch.Tensor]:
    return (torch.tensor([vocab.node(e["agent"]) for e in events], dtype=torch.long), torch.tensor([vocab.node(e["target"]) for e in events], dtype=torch.long),
            torch.tensor([vocab.kind(e["kind"]) for e in events], dtype=torch.long), torch.tensor([e["t"] for e in events], dtype=torch.float))


def batches(n: int, size: int):
    for i in range(0, n, size):
        yield slice(i, min(n, i + size))


def train(events: List[Dict[str, Any]], vocab: Vocab, seed: int = 1, epochs: int = 6, batch: int = 48, lr: float = 3e-3, d: int = 32, m: int = 8) -> Tuple["TGN", List[float]]:
    """Train on normal events only. Returns the model and the mean surprise of each epoch."""
    seed_everything(seed)
    model = TGN(len(vocab.nodes), len(vocab.kinds), d=d, m=m)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    src, dst, kind, t = tensors(events, vocab)
    curve: List[float] = []
    for _ in range(epochs):
        S = State(len(vocab.nodes), d, m)
        total, pending = 0.0, None
        for sl in batches(len(events), batch):
            if pending is not None:
                model.update(S, *pending)            # the previous batch enters the memory inside the graph, so the message and memory networks learn from the prediction that follows
            loss = model.predict(S, src[sl], dst[sl], kind[sl], t[sl]).mean()
            opt.zero_grad()
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            S.detach()
            pending = (src[sl], dst[sl], kind[sl], t[sl])
            total += loss.item() * (sl.stop - sl.start)
        curve.append(total / len(events))
    return model, curve


@torch.no_grad()
def surprises(model: TGN, vocab: Vocab, events: List[Dict[str, Any]], batch: int = 48) -> List[float]:
    """The surprise of every event of a time-ordered stream, replayed from an empty memory."""
    model.eval()
    S = State(len(vocab.nodes), model.d, model.m)
    src, dst, kind, t = tensors(events, vocab)
    out: List[float] = []
    for sl in batches(len(events), batch):
        out += model.predict(S, src[sl], dst[sl], kind[sl], t[sl]).tolist()
        model.update(S, src[sl], dst[sl], kind[sl], t[sl])
    return out


def state_dict_checksum(model: TGN) -> str:
    """A hash of the weights, so a recorded evaluation names exactly the model it judged."""
    import hashlib
    h = hashlib.sha256()
    for k, v in sorted(model.state_dict().items()):
        h.update(k.encode())
        h.update(",".join(f"{x:.7e}" for x in v.detach().flatten().tolist()).encode())
    return h.hexdigest()

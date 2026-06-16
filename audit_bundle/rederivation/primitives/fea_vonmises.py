"""fea_vonmises_recompute — verifier-side FEA von-Mises re-derivation.

Axis-2 value-return form of the FEA re-derivation (the fused
the FEA pilot, split into recompute +
compare). The exemplar's representative output is the scalar `sigma_vm_max` (max
von-Mises stress); the bound comparator is `scalar_epsilon` with the acceptance
epsilon read from the AUDITOR-ANCHORED binding spec — NOT from the producer's
solver_config (Path-β: the acceptance criterion is authority-pinned, not
producer-asserted).

recompute(): loads inputs/{mesh,material,bcs}.json + the SOLVER parameters
(tol, max_iter) from spec/solver_config.json, runs a pure-Python 2D plane-stress
linear-elastic CST solve, and RETURNS sigma_vm_max. It does NOT read the
acceptance epsilon and does NOT compare — the verifier's scalar_epsilon
comparator (epsilon from the pinned spec) decides agreement against the claimed
value (outputs/<id>.json).

The CST kernel is duplicated verifier-side per AB4 (duplicate-don't-import); this
module is the authority. Stdlib-only (math).
"""

from __future__ import annotations

import math
from pathlib import Path

from ...admission import admit_json_file
from ...plugin import ParsedInputs, RecomputedValue
from ..registry import register_primitive


def _element_stiffness(p1, p2, p3, E, nu, t):
    x1, y1 = p1
    x2, y2 = p2
    x3, y3 = p3
    area2 = (x2 - x1) * (y3 - y1) - (x3 - x1) * (y2 - y1)
    A = abs(area2) / 2.0
    if A == 0.0:
        raise ValueError("degenerate triangle")
    b1 = y2 - y3
    c1 = x3 - x2
    b2 = y3 - y1
    c2 = x1 - x3
    b3 = y1 - y2
    c3 = x2 - x1
    inv2A = 1.0 / (2.0 * A)
    B = [
        [b1 * inv2A, 0.0, b2 * inv2A, 0.0, b3 * inv2A, 0.0],
        [0.0, c1 * inv2A, 0.0, c2 * inv2A, 0.0, c3 * inv2A],
        [c1 * inv2A, b1 * inv2A, c2 * inv2A, b2 * inv2A, c3 * inv2A, b3 * inv2A],
    ]
    coeff = E / (1.0 - nu * nu)
    D = [
        [coeff, coeff * nu, 0.0],
        [coeff * nu, coeff, 0.0],
        [0.0, 0.0, coeff * (1.0 - nu) / 2.0],
    ]
    DB = [
        [sum(D[i][k] * B[k][j] for k in range(3)) for j in range(6)] for i in range(3)
    ]
    Ke = [
        [A * t * sum(B[k][i] * DB[k][j] for k in range(3)) for j in range(6)]
        for i in range(6)
    ]
    return Ke, B, D, A


def _assemble_global(nodes, elements, E, nu, t):
    n_dofs = len(nodes) * 2
    K = [[0.0] * n_dofs for _ in range(n_dofs)]
    element_data = []
    for elem in elements:
        i, j, k = elem
        Ke, B, D, A = _element_stiffness(nodes[i], nodes[j], nodes[k], E, nu, t)
        dof_map = [2 * i, 2 * i + 1, 2 * j, 2 * j + 1, 2 * k, 2 * k + 1]
        for a in range(6):
            row_a = K[dof_map[a]]
            Ke_row = Ke[a]
            for b in range(6):
                row_a[dof_map[b]] += Ke_row[b]
        element_data.append((dof_map, B, D, A))
    return K, element_data


def _apply_dirichlet(K, f, dirichlet):
    n_dofs = len(f)
    for bc in dirichlet:
        dof = bc["node"] * 2 + (0 if bc["dof"] == "x" else 1)
        val = float(bc["value"])
        for j in range(n_dofs):
            K[dof][j] = 0.0
            K[j][dof] = 0.0
        K[dof][dof] = 1.0
        f[dof] = val


def _apply_neumann(f, neumann):
    for bc in neumann:
        dof = bc["node"] * 2 + (0 if bc["dof"] == "x" else 1)
        f[dof] += float(bc["value"])


def _cg_solve(K, f, tol, max_iter):
    n = len(f)
    u = [0.0] * n
    r = list(f)
    p = list(r)
    rs_old = sum(r[i] * r[i] for i in range(n))
    for _it in range(max_iter):
        Ap = [sum(K[i][j] * p[j] for j in range(n)) for i in range(n)]
        pAp = sum(p[i] * Ap[i] for i in range(n))
        if pAp == 0.0:
            break
        alpha = rs_old / pAp
        for i in range(n):
            u[i] += alpha * p[i]
            r[i] -= alpha * Ap[i]
        rs_new = sum(r[i] * r[i] for i in range(n))
        if math.sqrt(rs_new) <= tol:
            break
        beta = rs_new / rs_old
        for i in range(n):
            p[i] = r[i] + beta * p[i]
        rs_old = rs_new
    return u


def _stress_recovery(u, element_data):
    max_vm = 0.0
    for dof_map, B, D, _A in element_data:
        u_e = [u[d] for d in dof_map]
        strain = [sum(B[i][j] * u_e[j] for j in range(6)) for i in range(3)]
        stress = [sum(D[i][j] * strain[j] for j in range(3)) for i in range(3)]
        sx, sy, sxy = stress
        vm = math.sqrt(sx * sx - sx * sy + sy * sy + 3.0 * sxy * sxy)
        if vm > max_vm:
            max_vm = vm
    return max_vm


def compute_sigma_vm_max(bundle_dir: Path) -> float:
    """Canonical sigma_vm_max recompute. The build imports this so the honest
    producer's claimed value and the verifier's recompute share ONE definition."""
    # Admission-bounded loads (size/depth/cardinality) for each bundle-controlled
    # input — same discipline as manifest.json. InputInadmissible propagates →
    # dispatch records RECOMPUTE_ERROR.
    mesh = admit_json_file(bundle_dir / "inputs" / "mesh.json")
    material = admit_json_file(bundle_dir / "inputs" / "material.json")
    bcs = admit_json_file(bundle_dir / "inputs" / "bcs.json")
    solver_config = admit_json_file(bundle_dir / "spec" / "solver_config.json")

    nodes = mesh["nodes"]
    elements = mesh["elements"]
    K, element_data = _assemble_global(
        nodes,
        elements,
        float(material["E"]),
        float(material["nu"]),
        float(material["thickness"]),
    )
    n_dofs = len(nodes) * 2
    f = [0.0] * n_dofs
    _apply_neumann(f, bcs["neumann"])
    _apply_dirichlet(K, f, bcs["dirichlet"])
    tol = float(solver_config["tol"])
    max_iter = int(solver_config["max_iter"])
    u = _cg_solve(K, f, tol, max_iter)
    return _stress_recovery(u, element_data)


class FeaVonMisesRecompute:
    primitive_id: str = "fea_vonmises_recompute"

    def recompute(self, inputs: ParsedInputs, pack_section: dict) -> RecomputedValue:
        sigma = compute_sigma_vm_max(inputs.bundle_dir)
        return RecomputedValue(
            value=sigma, detail="re-derived sigma_vm_max via CST solve"
        )


register_primitive(FeaVonMisesRecompute())

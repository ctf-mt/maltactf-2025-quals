import itertools

from sage.all import Matrix, ZZ


def block_decomposition(M):
    """
    Given a 4x4 matrix, return the four 2x2 matrices as blocks
    """
    A = M.matrix_from_rows_and_columns([0, 1], [0, 1])
    B = M.matrix_from_rows_and_columns([2, 3], [0, 1])
    C = M.matrix_from_rows_and_columns([0, 1], [2, 3])
    D = M.matrix_from_rows_and_columns([2, 3], [2, 3])

    return A, B, C, D


def base_change_theta(M, zeta):
    r"""
    Computes the matrix N (in row convention) of the new level 2
    theta coordinates after a symplectic base change of A[4] given
    by M\in Sp_4(Z/4Z). We have:
    (theta'_i)=N*(theta_i)
    where the theta'_i are the new theta coordinates and theta_i,
    the theta coordinates induced by the product theta structure.
    N depends on the fourth root of unity zeta=e_4(Si,Ti) (where
    (S0,S1,T0,T1) is a symplectic basis if A[4]).

    Inputs:
    - M: symplectic base change matrix.
    - zeta: a primitive 4-th root of unity induced by the Weil-pairings
    of the symplectic basis of A[4].

    Output: Matrix N of base change of theta-coordinates.
    """
    # Split 4x4 matrix into 2x2 blocks
    A, B, C, D = block_decomposition(M)

    # Initialise N to 4x4 zero matrix
    N = [[0 for _ in range(4)] for _ in range(4)]

    def choose_non_vanishing_index(C, D, zeta):
        """
        Choice of reference non-vanishing index (ir0,ir1)
        """
        for ir0, ir1 in itertools.product([0, 1], repeat=2):
            L = [0, 0, 0, 0]
            for j0, j1 in itertools.product([0, 1], repeat=2):
                k0 = C[0, 0] * j0 + C[0, 1] * j1
                k1 = C[1, 0] * j0 + C[1, 1] * j1

                l0 = D[0, 0] * j0 + D[0, 1] * j1
                l1 = D[1, 0] * j0 + D[1, 1] * j1

                e = -(k0 + 2 * ir0) * l0 - (k1 + 2 * ir1) * l1
                L[ZZ(k0 + ir0) % 2 + 2 * (ZZ(k1 + ir1) % 2)] += zeta ** (ZZ(e))

            # Search if any L value in L is not zero
            if any([x != 0 for x in L]):
                return ir0, ir1

        raise ValueError("Never found vanishing index")

    ir0, ir1 = choose_non_vanishing_index(C, D, zeta)

    for i0, i1, j0, j1 in itertools.product([0, 1], repeat=4):
        k0 = A[0, 0] * i0 + A[0, 1] * i1 + C[0, 0] * j0 + C[0, 1] * j1
        k1 = A[1, 0] * i0 + A[1, 1] * i1 + C[1, 0] * j0 + C[1, 1] * j1

        l0 = B[0, 0] * i0 + B[0, 1] * i1 + D[0, 0] * j0 + D[0, 1] * j1
        l1 = B[1, 0] * i0 + B[1, 1] * i1 + D[1, 0] * j0 + D[1, 1] * j1

        e = i0 * j0 + i1 * j1 - (k0 + 2 * ir0) * l0 - (k1 + 2 * ir1) * l1
        N[i0 + 2 * i1][ZZ(k0 + ir0) % 2 + 2 * (ZZ(k1 + ir1) % 2)] += zeta ** (ZZ(e))

    return Matrix(N)

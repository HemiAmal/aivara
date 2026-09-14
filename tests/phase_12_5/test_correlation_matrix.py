"""Unit and invariant tests for 7x7 Correlation Matrix (Phase 12.5)."""

import math
import pytest

from aivara.universal.enums import SubsystemDomain
from aivara.universal.correlation import (
    CANONICAL_DOMAIN_ORDER,
    AsymmetricMatrixError,
    CorrelationMatrix,
    CorrelationOutOfRangeError,
    InvalidCorrelationMatrixError,
    InvalidDomainOrderError,
    NonFiniteCorrelationError,
    NonZeroDiagonalError,
)


def test_canonical_domain_order_exact():
    """Verify exact 7 canonical domains in authoritative Phase 12.1 order."""
    expected = [
        SubsystemDomain.DATASET_INTEGRITY,
        SubsystemDomain.CONTRIBUTOR_RISK,
        SubsystemDomain.MODEL_INTEGRITY,
        SubsystemDomain.BEHAVIORAL_ANALYSIS,
        SubsystemDomain.BACKDOOR_TRIGGER,
        SubsystemDomain.INFERENCE_INTEGRITY,
        SubsystemDomain.DISTRIBUTION_SHIFT,
    ]
    assert CANONICAL_DOMAIN_ORDER == expected


def test_default_canonical_matrix_validity():
    """Verify default canonical correlation matrix satisfies all structural invariants."""
    mat = CorrelationMatrix.create_default_canonical_matrix()

    assert mat.dimension == 7
    assert len(mat.domain_order) == 7
    assert len(mat.matrix_values) == 7
    assert len(mat.matrix_hash) == 64

    # Zero diagonal
    for i in range(7):
        assert mat.matrix_values[i][i] == 0.0

    # Symmetry
    for i in range(7):
        for j in range(7):
            assert mat.matrix_values[i][j] == mat.matrix_values[j][i]
            assert 0.0 <= mat.matrix_values[i][j] <= 1.0


def test_zero_matrix_validity():
    """Verify zero correlation matrix representing independent domains."""
    mat = CorrelationMatrix.create_zero_matrix()
    for i in range(7):
        for j in range(7):
            assert mat.matrix_values[i][j] == 0.0
    assert len(mat.matrix_hash) == 64


def test_matrix_hash_determinism_and_mutation():
    """Verify bit-exact hash determinism and mutation sensitivity."""
    mat1 = CorrelationMatrix.create_default_canonical_matrix()
    mat2 = CorrelationMatrix.create_default_canonical_matrix()
    assert mat1.matrix_hash == mat2.matrix_hash

    # Mutate one cell (preserving symmetry and zero diagonal)
    values = [row.copy() for row in mat1.matrix_values]
    values[0][1] = 0.99
    values[1][0] = 0.99
    mat_mutated = CorrelationMatrix(matrix_values=values)
    assert mat_mutated.matrix_hash != mat1.matrix_hash


def test_reject_asymmetric_matrix():
    """Verify asymmetric matrix is rejected with AsymmetricMatrixError."""
    values = [[0.0 for _ in range(7)] for _ in range(7)]
    values[0][1] = 0.50
    values[1][0] = 0.20  # Asymmetric!

    with pytest.raises(AsymmetricMatrixError):
        CorrelationMatrix(matrix_values=values)


def test_reject_non_zero_diagonal():
    """Verify matrix with non-zero diagonal entries is rejected with NonZeroDiagonalError."""
    values = [[0.0 for _ in range(7)] for _ in range(7)]
    values[2][2] = 0.10  # Non-zero diagonal!

    with pytest.raises(NonZeroDiagonalError):
        CorrelationMatrix(matrix_values=values)


def test_reject_out_of_range_values():
    """Verify values < 0.0 or > 1.0 are rejected with CorrelationOutOfRangeError."""
    values_neg = [[0.0 for _ in range(7)] for _ in range(7)]
    values_neg[0][1] = -0.05
    values_neg[1][0] = -0.05
    with pytest.raises(CorrelationOutOfRangeError):
        CorrelationMatrix(matrix_values=values_neg)

    values_high = [[0.0 for _ in range(7)] for _ in range(7)]
    values_high[0][1] = 1.05
    values_high[1][0] = 1.05
    with pytest.raises(CorrelationOutOfRangeError):
        CorrelationMatrix(matrix_values=values_high)


def test_reject_non_finite_values():
    """Verify NaN and Infinity values fail closed with NonFiniteCorrelationError."""
    values_nan = [[0.0 for _ in range(7)] for _ in range(7)]
    values_nan[0][1] = float("nan")
    values_nan[1][0] = float("nan")
    with pytest.raises(NonFiniteCorrelationError):
        CorrelationMatrix(matrix_values=values_nan)

    values_inf = [[0.0 for _ in range(7)] for _ in range(7)]
    values_inf[0][1] = float("inf")
    values_inf[1][0] = float("inf")
    with pytest.raises(NonFiniteCorrelationError):
        CorrelationMatrix(matrix_values=values_inf)


def test_reject_invalid_domain_order():
    """Verify non-canonical domain order is rejected with InvalidDomainOrderError."""
    values = [[0.0 for _ in range(7)] for _ in range(7)]
    inverted_order = list(reversed(CANONICAL_DOMAIN_ORDER))
    with pytest.raises(InvalidDomainOrderError):
        CorrelationMatrix(matrix_values=values, domain_order=inverted_order)

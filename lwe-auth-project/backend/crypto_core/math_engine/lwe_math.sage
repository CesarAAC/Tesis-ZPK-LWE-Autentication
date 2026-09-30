from sage.all import Matrix, Vector, ZZ, DiscreteGaussianDistributionIntegerSampler

def generate_lwe_instance(n, m, q, std_dev):
    # Muestra la matriz A en Z_q^(m x n)
    A = Matrix.random(ZZ, m, n, x=0, y=q)
    # Vector secreto s
    s = Vector([ZZ.random_element(0, q) for _ in range(n)])
    # Vector de error e muestreado de Gaussiana discreta
    sampler = DiscreteGaussianDistributionIntegerSampler(sigma=std_dev)
    e = Vector([sampler() for _ in range(m)])

    # b = A*s + e mod q
    b = (A * s + e) % q
    return A, s, b
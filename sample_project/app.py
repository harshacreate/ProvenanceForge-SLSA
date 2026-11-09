"""A trivial 'product' that the pipeline builds, inventories, and attests.

The point is not what this does, but that the pipeline can produce a verifiable
record of *how it was built* and detect tampering with the artifact, its
dependency inventory, or its provenance.
"""


def greet(name: str) -> str:
    return "hello, %s" % name


if __name__ == "__main__":
    print(greet("world"))

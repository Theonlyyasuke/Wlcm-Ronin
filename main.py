import mymath

def main():
    x = 10
    y = 5

    print(f"Addition of {x} and {y}: {mymath.add(x, y)}")
    print(f"Subtraction of {x} and {y}: {mymath.subtract(x, y)}")
    print(f"Multiplication of {x} and {y}: {mymath.multiply(x, y)}")
    print(f"Division of {x} and {y}: {mymath.divide(x, y)}")

if __name__ == "__main__":
    main()
import pandas as pd

df = pd. read_csv("myfile.csv")

print("Data in CSV file:")
print(df)

print("\nMean (average) of each column:")
print(df.mean(numeric_only=True))

print("\nMedian of each column:")
print(df.median(numeric_only=True))

print("\nSum of each column:")
print(df.sum(numeric_only=True))
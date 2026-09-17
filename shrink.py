import pandas as pd

print("Loading massive CSV...")
df = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")

# Separate the normal traffic from the hacker traffic
normal = df[df[' Label'].str.contains('BENIGN', na=False)]
attack = df[df[' Label'].str.contains('DDoS', na=False)]

print("Building the custom network sequence...")
# 1. Start with 100 normal packets (Graph is GOOD)
part1 = normal.iloc[0:100]

# 2. Hit them with a sudden 30-packet attack (First BIG SPIKE)
part2 = attack.iloc[0:30]

# 3. Go back to 50 normal packets (Graph is GOOD again)
part3 = normal.iloc[100:150]

# 4. A tiny 10-packet attack (LIGHTER SPIKE)
part4 = attack.iloc[30:40]

# 5. Back to 50 normal packets (Graph is GOOD)
part5 = normal.iloc[150:200]

# 6. Unleash a massive 150-packet attack (CONTINUOUS SPIKE)
part6 = attack.iloc[40:190]

# Tape all the clips together in exact order
final_df = pd.concat([part1, part2, part3, part4, part5, part6])

# Save the final highlight reel as a tiny file
final_df.to_csv("sample_traffic.csv", index=False)
print("Success! Rollercoaster CSV created.")

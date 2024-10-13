from scapy.all import sniff
import pandas as pd
import time
import matplotlib.pyplot as plt

# List to store captured packets
captured_packets = []

# Callback function to process each packet
def process_packet(packet):
    # Store packet summary in the list
    captured_packets.append({
        'time': time.time(),
        'summary': packet.summary()
    })

    # Print packet summary
    print(packet.summary())

# Sniff packets on the default network interface (timeout is 10 seconds)
sniff(timeout=10, prn=process_packet)

# Save captured packets to a CSV file
df = pd.DataFrame(captured_packets)
df.to_csv("captured_traffic.csv", index=False)

# Plot packet count over time
df['time'] = pd.to_datetime(df['time'], unit='s')
df['count'] = range(1, len(df) + 1)
plt.plot(df['time'], df['count'])
plt.title("Network Traffic Over Time")
plt.xlabel("Time")
plt.ylabel("Packet Count")
plt.show()

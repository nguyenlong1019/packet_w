import matplotlib.pyplot as plt
import numpy as np

# Tạo dữ liệu mẫu
x = np.linspace(0, 10, 100)
y = np.sin(x)

# Tạo biểu đồ progressive line
plt.figure(figsize=(10, 6))
for i in range(1, len(x)+1):
    plt.plot(x[:i], y[:i], color='blue')
    plt.pause(0.03)  # Tạm dừng để thấy được tiến trình

plt.title("Progressive Line Chart using Matplotlib")
plt.xlabel("X axis")
plt.ylabel("Y axis")
plt.show()

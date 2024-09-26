import plotly.graph_objs as go
import numpy as np
import time

# Tạo dữ liệu mẫu
x = np.linspace(0, 10, 100)
y = np.sin(x)

# Tạo biểu đồ rỗng ban đầu
fig = go.Figure()
fig.add_trace(go.Scatter(x=[], y=[], mode='lines', line=dict(color='blue')))

# Cập nhật từng bước
for i in range(len(x)):
    fig.update_traces(x=[x[:i+1]], y=[y[:i+1]])
    fig.show()
    time.sleep(0.1)  # Tạm dừng để thấy được tiến trình

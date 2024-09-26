const ctx = document.getElementById('pcapChart').getContext('2d');

const data = {
    labels: ['0:0', '15:3:675', '30:7:350', '45:11:25', '0:14:700', '15:18:375', '45:25:725'],
    datasets: [
        {
            label: 'Total',
            data: [21584.81, 15000, 18000, 16000, 17000, 14000, 19892],
            borderColor: 'rgba(75, 192, 192, 1)',
            backgroundColor: 'rgba(75, 192, 192, 0.2)',
            fill: true,
            tension: 0.4
        },
        {
            label: 'UDP',
            data: [0, 0, 0, 0, 19598, 0, 0],
            borderColor: 'rgba(255, 99, 132, 1)',
            backgroundColor: 'rgba(255, 99, 132, 0.2)',
            fill: true,
            tension: 0.4
        },
        {
            label: 'TCP',
            data: [0, 0, 0, 0, 0.294, 0, 0],
            borderColor: 'rgba(54, 162, 235, 1)',
            backgroundColor: 'rgba(54, 162, 235, 0.2)',
            fill: true,
            tension: 0.4
        },
        // Thêm các dataset khác cho các giao thức như HTTP, DNS,...
    ]
};

const config = {
    type: 'line',
    data: data,
    options: {
        scales: {
            x: {
                title: {
                    display: true,
                    text: 'Time'
                }
            },
            y: {
                title: {
                    display: true,
                    text: 'Data (kB)'
                }
            }
        },
        plugins: {
            tooltip: {
                mode: 'index',
                intersect: false
            },
            legend: {
                display: true,
                position: 'top'
            }
        }
    }
};

const pcapChart = new Chart(ctx, config);
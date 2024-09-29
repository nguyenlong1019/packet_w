fetch('chart_data.json')
    .then(response => response.json())
    .then(data => {
        const ctx = document.getElementById('pcapChart').getContext('2d');
        const pcapChart = new Chart(ctx, {
            type: 'line',
            data: data,
            options: {
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Time Intervals (seconds)'
                        }
                    },
                    y: {
                        title: {
                            display: true,
                            text: 'Data Size (kB)'
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
        });
    })
    .catch(error => console.error('Error loading chart data:', error));

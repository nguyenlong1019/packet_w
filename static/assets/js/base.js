window.addEventListener('DOMContentLoaded', function() {
    const notifyBtns = [...document.getElementsByClassName('.close-notify-btn')];
    notifyBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const targetId = btn.getAttribute('data-id');
            document.getElementById(targetId).classList.add('none');
        });
    });

    const pk = document.getElementById('default-key').value;

    let intervalId;
    const ctx = document.getElementById('pcapChart').getContext('2d'); 

    const datasets_samples = [
      {
        label: 'Total',
        data: [21584.81, 15000, 18000, 16000, 17000, 14000, 19892],
        borderColor: 'rgba(75, 192, 192, 1)',
        backgroundColor: 'rgba(75, 192, 192, 0.2)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'UDP',
        data: [0, 0, 0, 0, 19598, 0, 0],
        borderColor: 'rgba(255, 99, 132, 1)',
        backgroundColor: 'rgba(255, 99, 132, 0.2)',
        fill: true,
        tension: 0.4,
      },
      {
        label: 'TCP',
        data: [0, 0, 0, 0, 0.294, 0, 0],
        borderColor: 'rgba(54, 162, 235, 1)',
        backgroundColor: 'rgba(54, 162, 235, 0.2)',
        fill: true,
        tension: 0.4,
      }
    ];

    function checkStatus() {
      fetch(`check-status/${pk}`, {
        method: 'GET',
      })
      .then(response => response.json())
      .then(data => {
        if (data.flag) {
          clearInterval(intervalId);
          document.getElementById('loading').classList.add('d-none');
          getMainChartData();
        }
        return data.flag;
      })
      .catch(error => console.error(error));
      return false;
    }

    function getMainChartData() {
      fetch(`main-analysis/${pk}/`, {
        method: 'GET',
      })
      .then(response => response.json())
      .then(data => {
        if (data && data.labels && data.datasets) {
          drawChart(data.labels, data.datasets);
        } else {
          drawChart(
            ['0:0', '15:3:675', '30:7:350', '45:11:25', '0:14:700', '15:18:375', '45:25:725'], 
            datasets_samples,
          );
        }
      })  
      .catch((error) => {
        console.error(error);
        drawChart(
          ['0:0', '15:3:675', '30:7:350', '45:11:25', '0:14:700', '15:18:375', '45:25:725'], 
          datasets_samples,
        );
      });
    }

    function drawChart(labels, datasets) {
      const data = {
        labels: labels,
        datasets: datasets,
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

      // Tạo biểu đồ với Chart.js
      new Chart(ctx, config);
    }

    function startPolling() {
      intervalId = setInterval(() => {
        checkStatus().then(isTrue => {
          if (isTrue) {
            clearInterval(intervalId);
          }
        });
      }, 2000);
    }

    startPolling();
});


function openCTab(evt, elemId) {
    var i, tabcontent, tablinks;

    tabcontent = document.getElementsByClassName('c-tabcontent');
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }

    tablinks = document.getElementsByClassName('c-tablinks');
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }

    document.getElementById(elemId).style.display = "block";
    evt.currentTarget.className += " active";
}

document.getElementById("defaultOpen").click();


// Lấy tất cả các button và nội dung của tab
const tabLinks = document.querySelectorAll('.side-tablinks');
const tabContents = document.querySelectorAll('.side-tabcontent');

// Hàm chuyển đổi tab
function openTab(event, tabIndex) {
  // Loại bỏ class active cho tất cả các button và nội dung tab
  tabLinks.forEach(link => {
    link.classList.remove('btn-light');
    link.classList.add('btn-outline-light');
  });
  
  tabContents.forEach(content => {
    content.style.display = 'none';
  });

  // Thêm class active cho button được click và hiển thị nội dung tab tương ứng
  event.currentTarget.classList.remove('btn-outline-light');
  event.currentTarget.classList.add('btn-light');
  
  tabContents[tabIndex].style.display = 'block';
}

// Gán sự kiện click cho tất cả các button
tabLinks.forEach((link, index) => {
  link.addEventListener('click', function(event) {
    openTab(event, index);
  });
});

// Mặc định hiển thị tab đầu tiên
tabLinks[0].click();


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
          
          
          const frameBodyTable = document.getElementById('frame-body');
          const frames = data.frames;
          if (frames.length == 0) {
            frameBodyTable.innerHTML = `<p>Không có dữ liệu</p>`;
          } else {
            frames.forEach(item => {
              frameBodyTable.innerHTML += `
                <tr>
                  <th scope="row">${item[0]}</th>
                  <td>${item[1]}</td>
                  <td>${item[2]}</td>
                  <td>${item[3]}</td>
                  <td>${item[4]}</td>
                  <td>${item[5]}</td>
                  <td>${item[6]}</td>
                </tr>
              `;
            });
          }

          const tcp = data.tcp;
          const tcpBodyTable = document.getElementById('tcp-body');
          if (tcp.length == 0) {
            tcpBodyTable.innerHTML = `<p>Không có dữ liệu</p>`;
          } else {
            tcp.forEach(item => {
              tcpBodyTable.innerHTML += `
                <tr>
                  <th scope="row">${item[0]}</th>
                  <td>${item[1]}</td>
                  <td>${item[2]}</td>
                  <td>${item[3]}</td>
                  <td>${item[4]}</td>
                  <td>${item[5]}</td>
                  <td>${item[6]}</td>
                  <td>${item[3] + item[5]}</td>
                </tr>
              `;
            });
          }

          // const dns = data.dns;
          // const dnsBodyTable = document.getElementById('dns-body');
          // if (dns.length == 0) {
          //   dnsBodyTable.innerHTML = `<p>Không có dữ liệu</p>`;
          // } else {
          //   dns.forEach(item => {

          //   });
          // }

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

    const hexConvertBtn = document.getElementById('hexConvertBtn');
    hexConvertBtn.addEventListener('click', () => {
      const hexInput = document.getElementById('hexEncodedFormControlTextarea').value;
      const hexOutputElem = document.getElementById('hexDecodedFormControlTextarea');
      if (hexInput == '') {
        alert("Vui lòng nhập hex encoded string");
        return;
      }

      document.getElementById('overlay-utils').classList.remove('d-none');

      fetch('/convert/hex-decode/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value,
        },
        body: JSON.stringify({
          'hex_string': hexInput,
        })
      })
      .then(response => response.json())
      .then(data => {
        document.getElementById('overlay-utils').classList.add('d-none');
        hexOutputElem.value = data.res;
      })
      .catch(error => {
        document.getElementById('overlay-utils').classList.add('d-none');
        console.error(error);
        hexOutputElem.value = error;
      });
    });


    const base64ConvertBtn = document.getElementById('base64ConvertBtn');
    base64ConvertBtn.addEventListener('click', () => {
      const base64Input = document.getElementById('base64EncodedFormControlTextarea').value;
      const base64OutputElem = document.getElementById('base64DecodedFormControlTextarea1');
      if (base64Input == '') {
        alert("Vui lòng nhập base64 encoded string");
        return;
      }

      document.getElementById('overlay-utils').classList.remove('d-none');

      fetch('/convert/base64-decode/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value,
        },
        body: JSON.stringify({
          'encoded_string': base64Input,
        })
      })
      .then(response => response.json())
      .then(data => {
        document.getElementById('overlay-utils').classList.add('d-none');
        base64OutputElem.value = data.res;
      })
      .catch(error => {
        document.getElementById('overlay-utils').classList.add('d-none');
        console.error(error);
        base64OutputElem.value = error;
      });

    });

    const cTimeBtn = document.getElementById('cTimeBtn');
    cTimeBtn.addEventListener('click', () => {
      const selectType = document.getElementById('ctime-type').value;
      const cTimeInp = document.getElementById('ctimeInpFormControlTextarea').value;
      const cTimeOutElem = document.getElementById('ctimeOutFormControlTextarea');
      if (cTimeInp == '') {
        alert("Vui lòng nhập thời gian chuyển đổi");
        return;
      }

      document.getElementById('overlay-utils').classList.remove('d-none'); 

      fetch('/convert/c-time/', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-CSRFToken': document.querySelector('[name=csrfmiddlewaretoken]').value,
        },
        body: JSON.stringify({
          'ctype': selectType,
          'time_string': cTimeInp,
        })
      })
      .then(response => response.json())
      .then(data => {
        document.getElementById('overlay-utils').classList.add('d-none');
        cTimeOutElem.value = data.res;
      })
      .catch(error => {
        document.getElementById('overlay-utils').classList.add('d-none');
        console.error(error);
        cTimeOutElem.value = error;
      });

    });

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


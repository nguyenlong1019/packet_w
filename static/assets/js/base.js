window.addEventListener('DOMContentLoaded', function() {
    const notifyBtns = [...document.getElementsByClassName('.close-notify-btn')];
    notifyBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const targetId = btn.getAttribute('data-id');
            document.getElementById(targetId).classList.add('none');
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
    link.classList.remove('btn-primary');
    link.classList.add('btn-outline-primary');
  });
  
  tabContents.forEach(content => {
    content.style.display = 'none';
  });

  // Thêm class active cho button được click và hiển thị nội dung tab tương ứng
  event.currentTarget.classList.remove('btn-outline-primary');
  event.currentTarget.classList.add('btn-primary');
  
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


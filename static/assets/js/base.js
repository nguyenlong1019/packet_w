window.addEventListener('DOMContentLoaded', function() {
    const notifyBtns = [...document.getElementsByClassName('.close-notify-btn')];
    notifyBtns.forEach(btn => {
        btn.addEventListener('click', function() {
            const targetId = btn.getAttribute('data-id');
            document.getElementById(targetId).classList.add('none');
        });
    });
});
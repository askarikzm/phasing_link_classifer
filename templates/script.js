function circleMove() {
    window.addEventListener("mousemove", function(details) {
        document.querySelector("#minicircle").style.transform = `translate(${details.clientX}px, ${details.clientY}px)`;
    });
}

function firstPageAnim() {
    var t1 = gsap.timeline();
    t1.from("#form", {
        y: '-10',
        opacity: 0,
        ease: Expo.easeInOut,
        duration: 1.5
    });
}

circleMove();
firstPageAnim();

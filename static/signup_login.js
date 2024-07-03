document.addEventListener("DOMContentLoaded", () => {
    const signupButton = document.getElementById("signup-button"),
        loginButton = document.getElementById("login-button"),
        userForms = document.getElementById("user_options-forms");

    const toggleForms = (showSignup) => {
        if (showSignup) {
            userForms.classList.remove("bounceRight");
            userForms.classList.add("bounceLeft");
        } else {
            userForms.classList.remove("bounceLeft");
            userForms.classList.add("bounceRight");
        }
    };

    const checkUrlAndToggleForms = () => {
        const path = window.location.pathname;
        if (path.includes("register")) {
            toggleForms(true);
        } else if (path.includes("login")) {
            toggleForms(false);
        }
    };

    signupButton.addEventListener("click", (event) => {
        event.preventDefault();
        toggleForms(true);
        window.history.pushState(null, null, "/register");
    }, false);

    loginButton.addEventListener("click", (event) => {
        event.preventDefault();
        toggleForms(false);
        window.history.pushState(null, null, "/login");
    }, false);
    
    checkUrlAndToggleForms();
});

function visible_password(checkbox) {
    var passwordInput = checkbox.parentNode.previousElementSibling;
    if (checkbox.checked) {
        passwordInput.type = 'text';
    } else {
        passwordInput.type = 'password';
    }
}

// Login Script - Solo para página de login
document.addEventListener('DOMContentLoaded', function() {
    setupLoginForm();
    checkAuthStatus();
});

function setupLoginForm() {
    const loginForm = document.getElementById('loginForm');
    const loginBtn = document.getElementById('loginBtn');

    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();

        if (!username || !password) {
            showError('Por favor, completa todos los campos');
            return;
        }

        // Deshabilitar botón
        loginBtn.disabled = true;
        loginBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Iniciando sesión...';

        try {
            const response = await fetch('/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ username, password })
            });

            const data = await response.json();

            if (data.success) {
                showSuccess('Login exitoso, redirigiendo...');
                setTimeout(() => {
                    window.location.href = data.redirect || '/';
                }, 1500);
            } else {
                showError(data.message || 'Error de autenticación');
            }

        } catch (error) {
            console.error('Error en login:', error);
            showError('Error de conexión. Intenta nuevamente.');
        } finally {
            loginBtn.disabled = false;
            loginBtn.innerHTML = '<i class="fas fa-sign-in-alt"></i> Iniciar Sesión';
        }
    });
}

async function checkAuthStatus() {
    try {
        const response = await fetch('/api/current-user');
        if (response.ok) {
            const data = await response.json();
            if (data.success) {
                window.location.href = '/';
            }
        }
    } catch (error) {
        // No hacer nada, seguir en login
    }
}

function showError(message) {
    const errorDiv = document.getElementById('loginError');
    const errorMessage = document.getElementById('errorMessage');
    const successDiv = document.getElementById('loginSuccess');
    
    if (errorDiv && errorMessage) {
        errorMessage.textContent = message;
        errorDiv.style.display = 'flex';
        successDiv.style.display = 'none';
        
        // Auto ocultar después de 5 segundos
        setTimeout(() => {
            errorDiv.style.display = 'none';
        }, 5000);
    }
}

function showSuccess(message) {
    const successDiv = document.getElementById('loginSuccess');
    const successMessage = document.getElementById('successMessage');
    const errorDiv = document.getElementById('loginError');
    
    if (successDiv && successMessage) {
        successMessage.textContent = message;
        successDiv.style.display = 'flex';
        errorDiv.style.display = 'none';
    }
}
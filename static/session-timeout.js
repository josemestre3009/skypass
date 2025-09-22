// Sistema de timeout de sesión para páginas de admin
let timeoutId;
let warningShown = false;
const TIMEOUT_DURATION = 30000; // 30 segundos
const WARNING_TIME = 25000; // Mostrar aviso a los 25 segundos

function resetTimeout() {
    clearTimeout(timeoutId);
    warningShown = false;
    
    // Mostrar aviso a los 25 segundos
    timeoutId = setTimeout(() => {
        if (!warningShown) {
            showTimeoutWarning();
            warningShown = true;
        }
    }, WARNING_TIME);
}

function showTimeoutWarning() {
    Swal.fire({
        title: 'Sesión por expirar',
        text: 'Llevas 30 segundos sin actividad. Tu sesión se cerrará automáticamente.',
        icon: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Sigo aquí',
        cancelButtonText: 'Cerrar sesión',
        confirmButtonColor: '#28a745',
        cancelButtonColor: '#dc3545',
        timer: 5000,
        timerProgressBar: true,
        allowOutsideClick: false,
        allowEscapeKey: false
    }).then((result) => {
        if (result.isConfirmed) {
            // Renovar sesión
            fetch('/admin/renovar-sesion', {method: 'POST'})
                .then(() => {
                    resetTimeout();
                    Swal.fire({
                        title: 'Sesión renovada',
                        text: 'Tu sesión ha sido renovada exitosamente.',
                        icon: 'success',
                        timer: 2000,
                        showConfirmButton: false
                    });
                })
                .catch(() => {
                    window.location.href = '/admin/login';
                });
        } else if (result.dismiss === Swal.DismissReason.cancel) {
            // Cerrar sesión
            fetch('/admin/logout', {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        window.location.href = data.redirect || '/admin/login';
                    } else {
                        window.location.href = '/admin/login';
                    }
                })
                .catch(() => {
                    window.location.href = '/admin/login';
                });
        } else {
            // Timeout - cerrar sesión automáticamente
            fetch('/admin/logout', {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    if (data.success) {
                        window.location.href = data.redirect || '/admin/login';
                    } else {
                        window.location.href = '/admin/login';
                    }
                })
                .catch(() => {
                    window.location.href = '/admin/login';
                });
        }
    });
}

// Detectar actividad del usuario
function detectarActividad() {
    resetTimeout();
}

// Eventos que indican actividad
['mousedown', 'mousemove', 'keypress', 'scroll', 'touchstart', 'click'].forEach(event => {
    document.addEventListener(event, detectarActividad, true);
});

// Inicializar timeout al cargar la página
document.addEventListener('DOMContentLoaded', function() {
    resetTimeout();
});

// Sistema de timeout de sesión para páginas de admin
let timeoutId;
let warningShown = false;
const WARNING_TIME = 15 * 60 * 1000; // Aviso a los 15 minutos

function resetTimeout() {
    clearTimeout(timeoutId);
    warningShown = false;

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
        text: 'Llevas 15 minutos sin actividad. Tu sesión se cerrará automáticamente.',
        icon: 'warning',
        showCancelButton: true,
        confirmButtonText: 'Sigo aquí',
        cancelButtonText: 'Cerrar sesión',
        confirmButtonColor: '#28a745',
        cancelButtonColor: '#dc3545',
        timer: 10000,
        timerProgressBar: true,
        allowOutsideClick: false,
        allowEscapeKey: false
    }).then((result) => {
        //console.log('[SESSION] Resultado del modal:', result);
        if (result.isConfirmed) {
            // Renovar sesión
            //console.log('[SESSION] Renovando sesión...');
            fetch('/admin/renovar-sesion', {method: 'POST'})
                .then(response => {
                    //console.log('[SESSION] Respuesta renovar sesión:', response.status);
                    if (response.ok) {
                        resetTimeout();
                        Swal.fire({
                            title: 'Sesión renovada',
                            text: 'Tu sesión ha sido renovada exitosamente.',
                            icon: 'success',
                            timer: 2000,
                            showConfirmButton: false
                        });
                    } else {
                        throw new Error('Error renovando sesión');
                    }
                })
                .catch(error => {
                    //console.error('[SESSION] Error renovando sesión:', error);
                    window.location.href = '/admin/login';
                });
        } else if (result.dismiss === Swal.DismissReason.cancel) {
            // Cerrar sesión
            //console.log('[SESSION] Cerrando sesión manualmente...');
            fetch('/admin/logout', {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    //console.log('[SESSION] Respuesta logout:', data);
                    if (data.success) {
                        window.location.href = data.redirect || '/admin/login';
                    } else {
                        window.location.href = '/admin/login';
                    }
                })
                .catch(error => {
                    //console.error('[SESSION] Error en logout:', error);
                    window.location.href = '/admin/login';
                });
        } else {
            // Timeout - cerrar sesión automáticamente
            //console.log('[SESSION] Timeout automático - cerrando sesión...');
            fetch('/admin/logout', {method: 'POST'})
                .then(res => res.json())
                .then(data => {
                    //console.log('[SESSION] Respuesta logout automático:', data);
                    if (data.success) {
                        window.location.href = data.redirect || '/admin/login';
                    } else {
                        window.location.href = '/admin/login';
                    }
                })
                .catch(error => {
                    //console.error('[SESSION] Error en logout automático:', error);
                    window.location.href = '/admin/login';
                });
        }
    });
}

// Detectar actividad del usuario
function detectarActividad() {
    //  console.log('[SESSION] Actividad detectada');
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

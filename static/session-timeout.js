// Sistema de timeout de sesión para páginas de admin
let timeoutId;
let warningShown = false;
const TIMEOUT_DURATION = 60000; // 60 segundos
const WARNING_TIME = 50000; // Mostrar aviso a los 50 segundos

function resetTimeout() {
    clearTimeout(timeoutId);
    warningShown = false;
    
    //.log('[SESSION] Timeout reset - nuevo timeout iniciado');
    
    // Mostrar aviso a los 50 segundos
    timeoutId = setTimeout(() => {
        if (!warningShown) {
            //console.log('[SESSION] Mostrando aviso de timeout');
            showTimeoutWarning();
            warningShown = true;
        }
    }, WARNING_TIME);
}

function showTimeoutWarning() {
    //console.log('[SESSION] Ejecutando showTimeoutWarning');
    Swal.fire({
        title: 'Sesión por expirar',
        text: 'Llevas 60 segundos sin actividad. Tu sesión se cerrará automáticamente.',
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
    console.log('[SESSION] Inicializando sistema de timeout');
    resetTimeout();
});

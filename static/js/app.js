// IP Manager - Professional JavaScript Application
// Enhanced functionality with smooth animations and modern interactions

document.addEventListener('DOMContentLoaded', function() {
    initializeApp();
});

function initializeApp() {
    // Initialize tooltips
    initializeTooltips();
    
    // Initialize search functionality
    initializeSearch();
    
    // Initialize smooth animations
    initializeAnimations();
    
    // Initialize utility functions
    initializeUtilities();
    
    // Initialize copy functionality
    initializeCopyToClipboard();
}

// Initialize Bootstrap tooltips
function initializeTooltips() {
    if (typeof bootstrap !== 'undefined') {
        const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
        tooltipTriggerList.map(function (tooltipTriggerEl) {
            return new bootstrap.Tooltip(tooltipTriggerEl);
        });
    }
}

// Enhanced search functionality
function initializeSearch() {
    const searchInputs = document.querySelectorAll('.search-input, #searchInput');
    
    searchInputs.forEach(input => {
        if (input) {
            // Add debounced search
            let searchTimeout;
            input.addEventListener('input', function() {
                clearTimeout(searchTimeout);
                searchTimeout = setTimeout(() => {
                    if (typeof filterApplications === 'function') {
                        filterApplications();
                    }
                }, 300);
            });

            // Add focus effects
            input.addEventListener('focus', function() {
                const container = this.closest('.search-container');
                if (container) {
                    container.style.transform = 'scale(1.02)';
                }
            });

            input.addEventListener('blur', function() {
                const container = this.closest('.search-container');
                if (container) {
                    container.style.transform = 'scale(1)';
                }
            });
        }
    });
}

// Smooth animations and transitions
function initializeAnimations() {
    // Add fade-in effect to cards
    const cards = document.querySelectorAll('.card, .app-card, .stats-card');
    cards.forEach((card, index) => {
        card.style.opacity = '0';
        card.style.transform = 'translateY(20px)';
        
        setTimeout(() => {
            card.style.transition = 'all 0.5s ease-out';
            card.style.opacity = '1';
            card.style.transform = 'translateY(0)';
        }, index * 100);
    });

    // Add hover effects to interactive elements
    const interactiveElements = document.querySelectorAll('.btn, .app-card, .stats-card, .hover-lift');
    interactiveElements.forEach(element => {
        element.addEventListener('mouseenter', function() {
            if (!this.classList.contains('disabled')) {
                this.style.transform = this.classList.contains('app-card') || this.classList.contains('stats-card') 
                    ? 'translateY(-4px)' 
                    : 'translateY(-2px)';
            }
        });

        element.addEventListener('mouseleave', function() {
            this.style.transform = 'translateY(0)';
        });
    });
}

// Utility functions
function initializeUtilities() {
    // Auto-dismiss alerts
    setTimeout(() => {
        const alerts = document.querySelectorAll('.alert');
        alerts.forEach(alert => {
            if (alert && typeof bootstrap !== 'undefined') {
                const bsAlert = new bootstrap.Alert(alert);
                bsAlert.close();
            }
        });
    }, 5000);

    // Initialize form validation
    const forms = document.querySelectorAll('.needs-validation');
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            if (!form.checkValidity()) {
                event.preventDefault();
                event.stopPropagation();
            }
            form.classList.add('was-validated');
        });
    });

    // Initialize modals and dropdowns
    if (typeof bootstrap !== 'undefined') {
        // Auto-initialize all Bootstrap components
        const dropdowns = document.querySelectorAll('[data-bs-toggle="dropdown"]');
        dropdowns.forEach(dropdown => {
            new bootstrap.Dropdown(dropdown);
        });
    }
}

// Enhanced copy to clipboard functionality
function initializeCopyToClipboard() {
    window.copyToClipboard = function(text, customMessage = null) {
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(() => {
                showNotification('success', customMessage || `Copiado: ${text}`);
            }).catch(() => {
                fallbackCopyToClipboard(text, customMessage);
            });
        } else {
            fallbackCopyToClipboard(text, customMessage);
        }
    };

    function fallbackCopyToClipboard(text, customMessage) {
        const textArea = document.createElement('textarea');
        textArea.value = text;
        textArea.style.position = 'fixed';
        textArea.style.left = '-999999px';
        textArea.style.top = '-999999px';
        document.body.appendChild(textArea);
        textArea.focus();
        textArea.select();
        
        try {
            document.execCommand('copy');
            showNotification('success', customMessage || `Copiado: ${text}`);
        } catch (err) {
            showNotification('danger', 'Error al copiar al portapapeles');
        }
        
        document.body.removeChild(textArea);
    }
}

// Enhanced notification system
function showNotification(type, message, duration = 4000) {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} position-fixed`;
    notification.style.cssText = `
        top: 20px; 
        right: 20px; 
        z-index: 9999; 
        opacity: 0; 
        transition: all 0.3s ease;
        min-width: 300px;
        box-shadow: var(--shadow-lg);
        border: none;
    `;
    
    notification.innerHTML = `
        <div class="d-flex align-items-center">
            <i class="fas fa-${getIconForType(type)} me-2"></i>
            ${message}
        </div>
        <button type="button" class="btn-close" aria-label="Close"></button>
    `;
    
    document.body.appendChild(notification);
    
    // Fade in
    setTimeout(() => notification.style.opacity = '1', 100);
    
    // Auto-dismiss
    const dismissTimer = setTimeout(() => {
        notification.style.opacity = '0';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    }, duration);
    
    // Manual dismiss
    const closeBtn = notification.querySelector('.btn-close');
    closeBtn.addEventListener('click', () => {
        clearTimeout(dismissTimer);
        notification.style.opacity = '0';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.parentNode.removeChild(notification);
            }
        }, 300);
    });
}

function getIconForType(type) {
    switch(type) {
        case 'success': return 'check-circle';
        case 'danger': return 'exclamation-triangle';
        case 'warning': return 'exclamation-circle';
        case 'info': return 'info-circle';
        default: return 'bell';
    }
}

// Stats animation for dashboard
function animateStats() {
    const statsNumbers = document.querySelectorAll('.stats-number');
    
    statsNumbers.forEach(stat => {
        const finalValue = parseInt(stat.textContent) || 0;
        stat.textContent = '0';
        
        const duration = 2000;
        const increment = finalValue / (duration / 50);
        let current = 0;
        
        const timer = setInterval(() => {
            current += increment;
            if (current >= finalValue) {
                stat.textContent = finalValue;
                clearInterval(timer);
            } else {
                stat.textContent = Math.floor(current);
            }
        }, 50);
    });
}

// Enhanced application access function
function accessApp(appId, url) {
    // Show loading indicator
    showNotification('info', 'Abriendo aplicación...', 2000);
    
    // Log the access (if endpoint exists)
    if (appId) {
        fetch(`/api/log-access/${appId}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-Requested-With': 'XMLHttpRequest'
            }
        }).catch(() => {
            // Silently handle logging errors
        });
    }
    
    // Open the application
    if (url) {
        window.open(url, '_blank', 'noopener,noreferrer');
    }
}

// View toggle functionality for browse page
function toggleView(view) {
    const gridView = document.getElementById('gridView');
    const listView = document.getElementById('listView');
    const gridBtn = document.getElementById('gridViewBtn');
    const listBtn = document.getElementById('listViewBtn');

    if (!gridView || !listView || !gridBtn || !listBtn) return;

    if (view === 'grid') {
        gridView.classList.remove('d-none');
        listView.classList.add('d-none');
        gridBtn.classList.remove('btn-outline-primary');
        gridBtn.classList.add('btn-primary');
        listBtn.classList.remove('btn-primary');
        listBtn.classList.add('btn-outline-secondary');
    } else {
        gridView.classList.add('d-none');
        listView.classList.remove('d-none');
        listBtn.classList.remove('btn-outline-secondary');
        listBtn.classList.add('btn-primary');
        gridBtn.classList.remove('btn-primary');
        gridBtn.classList.add('btn-outline-primary');
    }
    
    // Store preference
    localStorage.setItem('preferredView', view);
}

// Filter applications functionality
function filterApplications() {
    const searchInput = document.getElementById('searchInput');
    const categoryFilter = document.getElementById('categoryFilter');
    const sortFilter = document.getElementById('sortFilter');
    
    if (!searchInput) return;
    
    const searchTerm = searchInput.value.toLowerCase();
    const categoryValue = categoryFilter ? categoryFilter.value : '';
    const sortValue = sortFilter ? sortFilter.value : '';
    
    const items = document.querySelectorAll('.application-item, .application-row');
    let visibleCount = 0;
    
    items.forEach(item => {
        const name = item.dataset.name || '';
        const ip = item.dataset.ip || '';
        const description = item.dataset.description || '';
        const category = item.dataset.category || '';
        
        const matchesSearch = !searchTerm || 
            name.includes(searchTerm) || 
            ip.includes(searchTerm) || 
            description.includes(searchTerm);
            
        const matchesCategory = !categoryValue || category === categoryValue;
        
        if (matchesSearch && matchesCategory) {
            item.style.display = '';
            visibleCount++;
        } else {
            item.style.display = 'none';
        }
    });
    
    // Show/hide no results message
    const noResults = document.getElementById('noResults');
    const applicationsContainer = document.getElementById('applicationsContainer');
    
    if (noResults && applicationsContainer) {
        if (visibleCount === 0 && (searchTerm || categoryValue)) {
            applicationsContainer.classList.add('d-none');
            noResults.classList.remove('d-none');
        } else {
            applicationsContainer.classList.remove('d-none');
            noResults.classList.add('d-none');
        }
    }
}

// Clear filters functionality
function clearFilters() {
    const searchInput = document.getElementById('searchInput');
    const categoryFilter = document.getElementById('categoryFilter');
    const sortFilter = document.getElementById('sortFilter');
    
    if (searchInput) searchInput.value = '';
    if (categoryFilter) categoryFilter.value = '';
    if (sortFilter) sortFilter.value = 'name';
    
    filterApplications();
}

// Load preferred view on page load
window.addEventListener('load', function() {
    const preferredView = localStorage.getItem('preferredView');
    if (preferredView && typeof toggleView === 'function') {
        toggleView(preferredView);
    }
    
    // Animate stats if on dashboard
    if (document.querySelector('.stats-number')) {
        setTimeout(animateStats, 500);
    }
});

// Enhanced form handling
function enhanceForm(formSelector) {
    const form = document.querySelector(formSelector);
    if (!form) return;
    
    form.addEventListener('submit', function(e) {
        const submitBtn = form.querySelector('button[type="submit"]');
        if (submitBtn) {
            const originalText = submitBtn.innerHTML;
            submitBtn.innerHTML = '<span class="loading-spinner me-2"></span>Procesando...';
            submitBtn.disabled = true;
            
            // Re-enable after 3 seconds as fallback
            setTimeout(() => {
                if (submitBtn.disabled) {
                    submitBtn.innerHTML = originalText;
                    submitBtn.disabled = false;
                }
            }, 3000);
        }
    });
}

// Initialize enhanced forms
document.addEventListener('DOMContentLoaded', function() {
    enhanceForm('#searchForm');
    enhanceForm('.needs-validation');
});

// Export functions for global use
window.IPManager = {
    showNotification,
    copyToClipboard: window.copyToClipboard,
    accessApp,
    toggleView,
    filterApplications,
    clearFilters,
    animateStats
};

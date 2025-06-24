(async function() {
    const container = document.getElementById('ad-container');
    
    const currentHost = window.location.hostname;
    const analyticsUrl = `http://${currentHost}:3000/ping`;
    
    try {
        await fetch(analyticsUrl);
        if (container && container.firstChild) {
            container.removeChild(container.firstChild);
        }
    } catch (error) {
        console.log('Analytics service not available');
    }
})(); 
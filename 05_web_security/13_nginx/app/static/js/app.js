// Crypto Tavern JavaScript

// Function to handle crypto purchase
function buyCrypto(symbol) {
    alert(`🎉 Purchase initiated for ${symbol}!\n\n` +
          `In a real application, this would:\n` +
          `- Process the transaction\n` +
          `- Update your wallet\n` +
          `- Confirm the purchase\n\n` +
          `But for now, enjoy the fantasy! 🪙`);
}

// Add smooth scroll behavior
document.addEventListener('DOMContentLoaded', function() {
    // Auto-hide flash messages after 5 seconds
    const flashMessages = document.querySelectorAll('.flash');
    flashMessages.forEach(function(message) {
        setTimeout(function() {
            message.style.transition = 'opacity 0.5s';
            message.style.opacity = '0';
            setTimeout(function() {
                message.remove();
            }, 500);
        }, 5000);
    });

    // Add animation to crypto cards
    const cryptoCards = document.querySelectorAll('.crypto-card');
    cryptoCards.forEach(function(card, index) {
        card.style.animation = `fadeInUp 0.5s ease ${index * 0.1}s`;
        card.style.opacity = '0';
        card.style.animationFillMode = 'forwards';
    });
});

// Add CSS animation keyframes dynamically
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeInUp {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);

// Console welcome message
console.log('%c🍺 Welcome to Crypto Tavern! 🪙',
    'font-size: 20px; font-weight: bold; color: #667eea;');
console.log('%cWhere Fantasy Meets Blockchain',
    'font-size: 14px; color: #764ba2; font-style: italic;');

// Modern SaasApp - Enhanced Interactions

document.addEventListener('DOMContentLoaded', function() {
  // Add page transition class
  document.body.classList.add('page-transition');
  
  // Navbar scroll effect
  const navbar = document.querySelector('.navbar-modern');
  let lastScroll = 0;
  
  window.addEventListener('scroll', function() {
    const currentScroll = window.pageYOffset;
    
    if (currentScroll > 50) {
      navbar.style.background = 'rgba(15, 23, 42, 0.95)';
      navbar.style.boxShadow = '0 4px 30px rgba(0, 0, 0, 0.3)';
    } else {
      navbar.style.background = 'rgba(15, 23, 42, 0.8)';
      navbar.style.boxShadow = 'none';
    }
    
    lastScroll = currentScroll;
  });
  
  // Form input animations
  const formInputs = document.querySelectorAll('.form-input');
  formInputs.forEach(input => {
    input.addEventListener('focus', function() {
      this.parentElement.classList.add('focused');
    });
    
    input.addEventListener('blur', function() {
      if (!this.value) {
        this.parentElement.classList.remove('focused');
      }
    });
  });
  
  // Button loading state
  const forms = document.querySelectorAll('form');
  forms.forEach(form => {
    form.addEventListener('submit', function(e) {
      const submitBtn = this.querySelector('button[type="submit"]');
      if (submitBtn) {
        const originalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<span class="loading"></span> Processing...';
        submitBtn.disabled = true;
        
        // Re-enable after 5 seconds in case of error
        setTimeout(() => {
          submitBtn.innerHTML = originalText;
          submitBtn.disabled = false;
        }, 5000);
      }
    });
  });
  
  // Pricing card hover synchronization
  const pricingCards = document.querySelectorAll('.pricing-card');
  pricingCards.forEach(card => {
    card.addEventListener('mouseenter', function() {
      pricingCards.forEach(c => {
        if (c !== this) {
          c.style.opacity = '0.7';
          c.style.transform = 'scale(0.98)';
        }
      });
    });
    
    card.addEventListener('mouseleave', function() {
      pricingCards.forEach(c => {
        c.style.opacity = '1';
        c.style.transform = '';
      });
    });
  });
  
  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });
  
  // Intersection Observer for scroll animations
  const observerOptions = {
    root: null,
    rootMargin: '0px',
    threshold: 0.1
  };
  
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }
    });
  }, observerOptions);
  
  // Observe cards for scroll animations
  document.querySelectorAll('.card-glass, .pricing-card, .auth-card').forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(20px)';
    el.style.transition = 'opacity 0.6s ease, transform 0.6s ease';
    observer.observe(el);
  });
  
  // Parallax effect for orbs
  const orbs = document.querySelectorAll('.orb');
  let ticking = false;
  
  window.addEventListener('mousemove', function(e) {
    if (!ticking) {
      window.requestAnimationFrame(function() {
        const mouseX = e.clientX / window.innerWidth;
        const mouseY = e.clientY / window.innerHeight;
        
        orbs.forEach((orb, index) => {
          const speed = (index + 1) * 20;
          const x = (window.innerWidth / 2 - e.clientX) / speed;
          const y = (window.innerHeight / 2 - e.clientY) / speed;
          orb.style.transform = `translate(${x}px, ${y}px)`;
        });
        
        ticking = false;
      });
      
      ticking = true;
    }
  });
  
  // Stats counter animation
  const stats = document.querySelectorAll('.stat-value');
  const animateCounter = (el) => {
    const text = el.textContent;
    const hasPlus = text.includes('+');
    const hasPercent = text.includes('%');
    const numericValue = parseInt(text.replace(/\D/g, ''));
    
    if (!isNaN(numericValue) && numericValue > 0) {
      let current = 0;
      const increment = numericValue / 50;
      const timer = setInterval(() => {
        current += increment;
        if (current >= numericValue) {
          current = numericValue;
          clearInterval(timer);
        }
        let display = Math.floor(current);
        if (hasPlus) display += 'K+';
        if (hasPercent) display += '%';
        if (text.includes('/')) display = current >= 24 ? '24/7' : display;
        el.textContent = display;
      }, 30);
    }
  };
  
  const statsObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        animateCounter(entry.target);
        statsObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.5 });
  
  stats.forEach(stat => statsObserver.observe(stat));
  
  // Ripple effect for buttons
  document.querySelectorAll('.btn').forEach(button => {
    button.addEventListener('click', function(e) {
      const ripple = document.createElement('span');
      const rect = this.getBoundingClientRect();
      const size = Math.max(rect.width, rect.height);
      const x = e.clientX - rect.left - size / 2;
      const y = e.clientY - rect.top - size / 2;
      
      ripple.style.cssText = `
        position: absolute;
        width: ${size}px;
        height: ${size}px;
        left: ${x}px;
        top: ${y}px;
        background: rgba(255, 255, 255, 0.3);
        border-radius: 50%;
        transform: scale(0);
        animation: ripple 0.6s ease-out;
        pointer-events: none;
      `;
      
      this.style.position = 'relative';
      this.style.overflow = 'hidden';
      this.appendChild(ripple);
      
      setTimeout(() => ripple.remove(), 600);
    });
  });
  
  // Add ripple keyframes
  const style = document.createElement('style');
  style.textContent = `
    @keyframes ripple {
      to {
        transform: scale(2);
        opacity: 0;
      }
    }
  `;
  document.head.appendChild(style);
});

// Utility function for debouncing
function debounce(func, wait) {
  let timeout;
  return function executedFunction(...args) {
    const later = () => {
      clearTimeout(timeout);
      func(...args);
    };
    clearTimeout(timeout);
    timeout = setTimeout(later, wait);
  };
}

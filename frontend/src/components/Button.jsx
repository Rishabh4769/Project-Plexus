import React from 'react';
import styles from './Button.module.css';

export default function Button({ 
  children, 
  variant = 'primary', 
  loading = false, 
  disabled = false, 
  className = '',
  ...props 
}) {
  const baseClass = styles.button;
  const variantClass = styles[variant] || styles.primary;
  
  return (
    <button 
      className={`${baseClass} ${variantClass} ${className} ${loading ? styles.loading : ''}`} 
      disabled={disabled || loading}
      {...props}
    >
      {loading && (
        <span className={styles.spinner}>
          <svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
            <circle className={styles.spinnerCircle} cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
          </svg>
        </span>
      )}
      <span className={styles.content}>{children}</span>
    </button>
  );
}

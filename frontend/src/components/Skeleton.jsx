import React from 'react';
import styles from './Skeleton.module.css';

export default function Skeleton({ width = '100%', height = '20px', borderRadius = 'var(--radius-sm)', className = '', style = {} }) {
  return (
    <div 
      className={`${styles.skeleton} ${className}`} 
      style={{ width, height, borderRadius, ...style }} 
    />
  );
}

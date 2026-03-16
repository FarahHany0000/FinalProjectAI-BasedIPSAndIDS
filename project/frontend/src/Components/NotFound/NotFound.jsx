import React from 'react';
import { Link } from 'react-router-dom';

export default function NotFound() {
  return (
    <div className='notfound'>
      <h1>404 - Page Not Found</h1>
      <p>The page you are looking for does not exist.</p>
      <Link to="/">Go back to Login</Link>
    </div>
  );
}

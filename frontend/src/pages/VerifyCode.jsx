import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';

const VerifyCode = () => {
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const location = useLocation();
  const email = location.state?.email;

  const handleVerify = async (e) => {
    e.preventDefault();
    setError('');

    try {
      const res = await fetch('http://localhost:4000/api/auth/verify-code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, code }),
      });
      const data = await res.json();
      if (res.ok) {
        navigate('/complete-profile', { state: { email } });
      } else {
        setError(data.error || 'Invalid code');
      }
    } catch {
      setError('Something went wrong');
    }
  };

  return (
    <div className="flex flex-col items-center justify-center min-h-screen bg-purple-50">
      <div className="bg-white rounded-2xl shadow-xl p-8 w-96 sm:w-[400px]">
        <h1 className="text-3xl font-bold text-center text-purple-600 mb-6">Verify Code</h1>
        <form onSubmit={handleVerify} className="space-y-3">
          <input
            type="text"
            placeholder="Enter 6-digit code"
            className="w-full p-3 border rounded-lg"
            value={code}
            onChange={(e) => setCode(e.target.value)}
            required
          />
          {error && <p className="text-red-600 text-sm">{error}</p>}
          <button
            type="submit"
            className="w-full py-3 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition"
          >
            Verify
          </button>
        </form>
      </div>
    </div>
  );
};

export default VerifyCode;

"use client";

export default function SignupPage() {
  return (
    <form>
      <h1>Create your account</h1>
      <label>
        Date of birth <input name="dob" type="date" />
      </label>
      <p>You must be 13 or older. We block under-13 signups.</p>
      <input name="email" type="email" />
      <input name="password" type="password" />
      <button type="submit">Sign up</button>
    </form>
  );
}

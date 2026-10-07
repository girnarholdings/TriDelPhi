"use client";

import { createUserWithEmailAndPassword } from "firebase/auth";

export default function SignupPage() {
  return (
    <form
      onSubmit={() => {
        createUserWithEmailAndPassword(auth, email, password);
      }}
    >
      <h1>Create your account</h1>
      <input name="email" type="email" />
      <input name="password" type="password" />
      <button type="submit">Sign up</button>
    </form>
  );
}

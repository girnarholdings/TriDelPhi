export default function Signup() {
  async function onSubmit() {
    await supabase.auth.signUp({ email, password });
  }
  return (
    <form onSubmit={onSubmit}>
      <h1>Create your account</h1>
      <input name="email" type="email" />
      <input name="password" type="password" />
      <button type="submit">Sign up</button>
    </form>
  );
}

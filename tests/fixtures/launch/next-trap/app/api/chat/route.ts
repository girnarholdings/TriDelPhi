export async function POST(req: Request) {
  const body = await req.json();
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: body.message }],
  });
  return Response.json(completion);
}

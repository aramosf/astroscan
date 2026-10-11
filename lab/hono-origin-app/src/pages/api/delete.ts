export const prerender = false;

let mutations = 0;

export const POST: APIRoute = async () => {
  mutations += 1;
  return new Response(JSON.stringify({ mutations }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });
};

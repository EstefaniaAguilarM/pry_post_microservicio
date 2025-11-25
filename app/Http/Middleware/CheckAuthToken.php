<?php
namespace App\Http\Middleware;
use Closure;
use Illuminate\Http\Request;
use GuzzleHttp\Client;

class CheckAuthToken
{
    protected $authServiceUrl;

    public function __construct()
    {
        // URL pública del microservicio de autenticación
        $this->authServiceUrl = env('AUTH_SERVICE_URL', 'http://127.0.0.1:8000');
    }

    public function handle(Request $request, Closure $next)
    {
        $authHeader = $request->header('Authorization');
        if (!$authHeader || !preg_match('/Bearer\s+(.*)/i', $authHeader, $matches)) {
            return response()->json(['message'=>'Token no proporcionado'],401);
        }
        $token = $matches[1];

        // Llamada a /api/validate-token del auth service
        $client = new Client(['verify'=>false,'timeout'=>5]);

        try {
            $response = $client->request('GET', rtrim($this->authServiceUrl, '/').'/api/validate-token', [
                'headers' => [
                    'Authorization' => 'Bearer '.$token,
                    'Accept' => 'application/json',
                ],
            ]);
        } catch (\GuzzleHttp\Exception\ClientException $e) {
            // 4xx errors
            $body = $e->getResponse() ? json_decode((string)$e->getResponse()->getBody(), true) : null;
            return response()->json(['message' => $body['message'] ?? 'Token inválido'], 401);
        } catch (\Exception $e) {
            // Network or other error
            return response()->json(['message'=>'Error al validar token: '.$e->getMessage()], 500);
        }

        $data = json_decode((string)$response->getBody(), true);
        if (!isset($data['valid']) || $data['valid'] !== true) {
            return response()->json(['message'=>'Token inválido'],401);
        }

        // opcional: adjuntar info del usuario validado al request
        if (isset($data['user'])) {
            $request->attributes->set('auth_user', $data['user']);
        }

        return $next($request);
    }
}

<?php
namespace BookStack\Http\Middleware;

use BookStack\Users\Models\User;
use Closure;

class TokenAuthMiddleware
{
    public function handle($request, Closure $next)
    {
        $token = $request->query('auth_token');

        if (!$token) {
            return $next($request);
        }

        try {
            // Расшифровка токена
            $secretKey = env('BOOKSTACK_SECRET');
            $cipher = 'aes-256-cbc';

            // Разделение токена на данные и IV
            $decodedToken = base64_decode($token);
            [$encryptedData, $encodedIv] = explode('::', $decodedToken);
            $iv = base64_decode($encodedIv);

            $decryptedData = openssl_decrypt($encryptedData, $cipher, $secretKey, 0, $iv);

            $data = json_decode($decryptedData, true);

            // Проверка валидности токена
            if (!isset($data['phone'], $data['timestamp'])) {
                throw new \Exception('Invalid token format.');
            }

            if (now()->timestamp - $data['timestamp'] > 300) { // 300 секунд (5 минут)
                throw new \Exception('Token expired.');
            }

            // Найти пользователя по номеру телефона
            $user = User::where('phone', $data['phone'])->first();

            if (!$user) {
                throw new \Exception('User not found.');
            }


            // Авторизовать пользователя
            auth()->login($user);

        } catch (\Exception $e) {
            return redirect('/login')->with('error', 'Invalid or expired token.');
        }

        return $next($request);
    }
}

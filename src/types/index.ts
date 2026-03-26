export interface User {
  id: string;
  name: string;
  email: string;
  password_hash: string;
  created_at: Date;
}

export type PublicUser = Omit<User, 'password_hash'>;

export interface JwtPayload {
  sub: string;
  email: string;
}

export interface RefreshToken {
  id: string;
  user_id: string;
  family_id: string;
  token: string;
  expires_at: Date;
  created_at: Date;
  consumed_at: Date | null;
}

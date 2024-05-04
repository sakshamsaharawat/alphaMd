import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { MongooseModule } from '@nestjs/mongoose';
import { UserSchema } from './entities/user.entity';
import { JwtModule } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { PassportModule } from '@nestjs/passport';

@Module({
  imports: [PassportModule.register({ defaultStrategy: 'jwt' }),
  JwtModule.registerAsync({
    inject: [ConfigService],
    useFactory: async (config: ConfigService) => {
      try {
        const secret = config.get<string>('JWT_SECRET');
        const expiresIn = config.get<string | number>('EXPIRES_IN');

        if (!secret || !expiresIn) {
          throw new Error('JWT configuration missing in application config');
        }

        return {
          secret,
          signOptions: { expiresIn },
        };
      } catch (error) {
        throw new Error(`Failed to configure JWT: ${error.message}`);
      }
    },
  }),

  MongooseModule.forFeature([{ name: 'User', schema: UserSchema }])
  ],
  controllers: [UserController],
  providers: [UserService]
})
export class UserModule { }

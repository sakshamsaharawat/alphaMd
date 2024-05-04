import { IsString, IsEmail, IsNotEmpty, Matches, IsEnum, IsOptional, MinLength } from 'class-validator';
import { UserRole } from '../enum/user-enum';
import { Transform } from 'class-transformer';

export class CreateUserDto {
  @IsNotEmpty()
  @IsString()
  @IsEnum(UserRole)
  role: string;

  @IsOptional()
  @IsNotEmpty()
  @Transform(({ value }) => value.trim())
  firstName: string;

  @IsOptional()
  @IsNotEmpty()
  @Transform(({ value }) => value.trim())
  lastName: string;

  @IsOptional()
  @IsNotEmpty()
  @IsString()
  @Transform(({ value }) => value.trim())
  hospitalName: string;

  @IsNotEmpty()
  @IsEmail()
  email: string;

  @IsNotEmpty()
  @MinLength(6)
  password: string;

  @IsNotEmpty()
  @Matches(/^[0-9]{10}$/, { message: "NPI number must be valid" })
  npiNumber: string;
}


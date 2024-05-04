import { IsEmail, IsNotEmpty, IsNumber, IsString } from "class-validator";

export class ResetUserPasswordDto {

    @IsString()
    @IsEmail()
    email: string;

    @IsNumber()
    @IsNotEmpty()
    otp: number;

    @IsString()
    @IsNotEmpty()
    newPassword: string
}
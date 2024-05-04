import { IsEmail, IsString } from "class-validator";

export class ForgotUserPasswordDto {
    @IsString()
    @IsEmail()
    email: string;
}
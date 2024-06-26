import { IsNotEmpty, IsString } from "class-validator";

export class ChangeUserPasswordDto {

    @IsString()
    email: string;

    @IsString()
    @IsNotEmpty()
    oldPassword: string;

    @IsString()
    @IsNotEmpty()
    newPassword: string
}
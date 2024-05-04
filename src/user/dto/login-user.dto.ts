import {IsNotEmpty, IsOptional, IsString } from "class-validator";

export class LoginUserDto {

    @IsString()
    email: string;

    @IsOptional()
    @IsNotEmpty()
    password: string;
}
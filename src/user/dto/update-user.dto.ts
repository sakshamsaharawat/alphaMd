import { IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { Transform } from 'class-transformer';

export class UpdateUserDto {

    @IsString()
    @IsOptional()
    @IsNotEmpty()
    @Transform(({ value }) => value.trim())
    profileUrl: string;

    @IsString()
    @IsOptional()
    @IsNotEmpty()
    @Transform(({ value }) => value.trim())
    profileCoverUrl: string;

    @IsString()
    @IsOptional()
    @IsNotEmpty()
    @Transform(({ value }) => value.trim())
    logoUrl: string;

    @IsOptional()
    @IsString()
    @IsNotEmpty()
    @Transform(({ value }) => value.trim())
    clinicCoverProfileUrl: string;

}

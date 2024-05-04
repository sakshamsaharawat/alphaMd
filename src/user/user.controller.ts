import { Controller, Get, Post, Body, Patch, Param, Delete } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { CreateUser } from 'src/user/interface/create-user.interface';
import { UserProfile } from './interface/update-profile.interface';
import { LoginUserDto } from './dto/login-user.dto';
import { LoginUser } from './interface/login-user-interface';
import { ChangeUserPasswordDto } from './dto/change-user-password.dto';
import { BooleanMessage } from './interface/boolean-message.interface';
import { ResetUserPasswordDto } from './dto/reset-user-password.dto';


@Controller('user')
export class UserController {
  constructor(private readonly userService: UserService) { }

  @Post('create')
  create(@Body() createUserDto: CreateUserDto): Promise<CreateUser> {
    return this.userService.create(createUserDto);
  };

  @Post('login')
  login(@Body() loginUserDto: LoginUserDto): Promise<LoginUser> {
    return this.userService.login(loginUserDto);
  };

  @Post('forgot-password')
  forgotPassword(@Body('email') email: string) {
    return this.userService.forgotPassword(email)
  }

  @Post('change-password')
  changeUserPassword(@Body() changeUserPasswordDto: ChangeUserPasswordDto): Promise<BooleanMessage> {
    return this.userService.changeUserPassword(changeUserPasswordDto)
  }

  @Post('reset-password')
  resetPassword(@Body() resetUserPasswordDto: ResetUserPasswordDto): Promise<BooleanMessage> {
    return this.userService.resetPassword(resetUserPasswordDto)
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return this.userService.findOne(+id);
  };

  @Patch(':id')
  updateProfile(@Param('id') id: string, @Body() updateUserDto: UpdateUserDto): Promise<UserProfile> {
    return this.userService.updateProfile(id, updateUserDto);
  };

  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.userService.remove(+id);
  };
};

import { BooleanMessage } from './interface/boolean-message.interface';
import { BadRequestException, Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException } from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import { User } from './entities/user.entity';
import { UserRole } from './enum/user-enum';
import { LoginUserDto } from './dto/login-user.dto';
import { UserProfile } from './interface/update-profile.interface';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { LoginUser } from './interface/login-user-interface';
import { ChangeUserPasswordDto } from './dto/change-user-password.dto';
import * as randomstring from 'randomstring';
import * as nodemailer from 'nodemailer';
import { ConfigService } from '@nestjs/config';
import { ResetUserPasswordDto } from './dto/reset-user-password.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectModel('User')
    private readonly userModel: Model<User>,
    private jwtService: JwtService,
    private readonly configService: ConfigService
  ) { }

  async create(createUserDto: CreateUserDto): Promise<any> {
    const isEmailExist = await this.userModel.findOne({ email: createUserDto.email.toLowerCase() });
    if (isEmailExist) {
      throw new BadRequestException('Email already exists.');
    }

    const isNpiNumberExists = await this.userModel.findOne({ npiNumber: createUserDto.npiNumber });
    if (isNpiNumberExists) {
    }
    const saltOrRounds = 10;
    const newUser = new User();
    newUser.role = createUserDto.role;
    newUser.email = createUserDto.email.toLowerCase();
    newUser.npiNumber = createUserDto.npiNumber;
    const password = createUserDto.password;
    const hash = await bcrypt.hash(password, saltOrRounds);
    newUser.password = hash;

    switch (createUserDto.role) {
      case UserRole.PHYSICIAN:
        if (!createUserDto.firstName || !createUserDto.lastName) {
          throw new BadRequestException('First name and last name are required for physicians.');
        }
        newUser.firstName = createUserDto.firstName;
        newUser.lastName = createUserDto.lastName;
        break;
      case UserRole.CLINIC:
        if (!createUserDto.hospitalName) {
          throw new BadRequestException('Hospital name is required for clinics.');
        }
        newUser.hospitalName = createUserDto.hospitalName;
        break;
      default:
        throw new BadRequestException('Invalid role provided.');
    }
    await this.userModel.create(newUser);
    return { success: true, message: "User created successfully.", newUser };
  }

  async login(loginUserDto: LoginUserDto): Promise<LoginUser> {
    try {

      const user = await this.userModel.findOne({ email: loginUserDto.email.toLowerCase() }).select(['+password', '+email']);
      if (!user) {
        throw new UnauthorizedException("User not found. Please check your email.");
      }
      const passwordMatch = await bcrypt.compare(loginUserDto.password, user.password);
      if (!passwordMatch) {
        throw new UnauthorizedException("Incorrect password. Please try again.");
      }
      const payload = { email: user.email };
      const token = await this.jwtService.signAsync(payload);
      return { success: true, message: 'Login successfully', token };
    } catch (error) {
      console.error(error);
      throw new BadRequestException('Somthing went wrong.')
    }
  }

  async changeUserPassword(changeUserPasswordDto: ChangeUserPasswordDto): Promise<BooleanMessage> {
    try {
      const user = await this.userModel.findOne({ email: changeUserPasswordDto.email.toLowerCase() }).select(['+password'])
      if (!user) {
        throw new NotFoundException('User not found');
      }
      const isMatch = await bcrypt.compare(changeUserPasswordDto.oldPassword, user.password);
      if (!isMatch) {
        throw new UnauthorizedException({
          success: false,
          message: "Invalid credentials"
        });
      }
      const hashedPassword = await bcrypt.hash(changeUserPasswordDto.newPassword, 10);
      user.password = hashedPassword;
      await user.save();

      return { success: true, message: 'Password changed successfully' };
    } catch (error) {
      console.error(error);
      throw new InternalServerErrorException('Somthing went wrong.');
    }
  }

  async forgotPassword(email: string): Promise<boolean> {
    const user = await this.userModel.findOne({ email });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    const currentTime = new Date();
    const tenMinutesAgo = new Date(currentTime.getTime() - 10 * 60 * 1000);
    const otpRequests = await this.userModel.countDocuments({
      _id: user._id,
      otpRequestTimestamp: { $gte: tenMinutesAgo }
    });

    if (otpRequests >= 5) {
      throw new Error('OTP request limit exceeded. Please try again later.');
    }
    const otp = randomstring.generate({ length: 6, charset: 'numeric' });
    await this.userModel.findByIdAndUpdate(user._id, { $set: { otp, otpUsed: false, otpRequestTimestamp: new Date(currentTime.getTime() + 1 * 60 * 1000) } });
    try {
      return await this.sendOTPEmail(email, otp);
    } catch (error) {
      throw new Error(`Error sending OTP email: ${error.message}`);
    }
  }

  async sendOTPEmail(email: string, otp: string): Promise<boolean> {
    const transporter = nodemailer.createTransport({
      service: 'Gmail',
      auth: {
        user: this.configService.get<string>('EMAIL_USERNAME'),
        pass: this.configService.get<string>('EMAIL_PASSWORD'),
      },
    });

    const mailOptions = {
      from: this.configService.get<string>('EMAIL_USERNAME'),
      to: email,
      subject: 'Password Reset OTP',
      text: `Your OTP for password reset is: ${otp}`
    };

    try {
      const info = await transporter.sendMail(mailOptions);
      console.log('Email sent: ', info.response);
      return true;
    } catch (error) {
      console.error('Error sending email: ', error);
      return false;
    }
  }

  async resetPassword(resetUserPasswordDto: ResetUserPasswordDto): Promise<BooleanMessage> {
    const user = await this.userModel.findOne({ email: resetUserPasswordDto.email.toLowerCase() });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    if (user.otp != resetUserPasswordDto.otp || user.otpUsed || user.otpRequestTimestamp < new Date()) {
      throw new BadRequestException('Invalid or expired OTP');
    }

    const hashedPassword = await bcrypt.hash(resetUserPasswordDto.newPassword, 10);
    await this.userModel.findByIdAndUpdate(user._id, { $set: { password: hashedPassword, otpUsed: true } });;
    return { success: true, message: 'Password reset successfully.' }
  }

  findOne(id: number) {
    return `This action returns a #${id} user`;
  }

  async updateProfile(id: string, updateUserDto: UpdateUserDto): Promise<UserProfile> {
    const user = await this.userModel.findById(id);
    if (!user) {
      throw new NotFoundException('User not found.');
    }

    if (user.role === UserRole.PHYSICIAN) {
      user.profileUrl = updateUserDto.profileUrl;
      user.profileCoverUrl = updateUserDto.profileCoverUrl;
    } else if (user.role === UserRole.CLINIC) {
      user.logoUrl = updateUserDto.logoUrl;
      user.clinicCoverProfileUrl = updateUserDto.clinicCoverProfileUrl;
    } else {
      throw new BadRequestException('Invalid role provided.');
    }
    await user.save();
    return { success: true, message: 'Profile updated.', user };
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }
}

import { Prop, Schema, SchemaFactory } from "@nestjs/mongoose"
import { UserRole } from "../enum/user-enum"

@Schema()
export class User {
    @Prop({ type: String, required: true, enum: UserRole })
    role: string;

    @Prop({ type: String })
    firstName: string;

    @Prop({ type: String })
    lastName: string;

    @Prop({ type: String, required: true })
    email: string;

    @Prop({ type: String, required: true, select: false })
    password: string;

    @Prop({ type: String })
    hospitalName: string;

    @Prop({ type: String, required: true, unique: true })
    npiNumber: string;

    @Prop({ type: String })
    profileUrl: string;

    @Prop({ type: String })
    profileCoverUrl: string;

    @Prop({ type: String })
    logoUrl: string;

    @Prop({ type: String })
    clinicCoverProfileUrl: string;

    @Prop({ type: Number })
    otp: number

    @Prop({ type: Boolean, default: false })
    otpUsed: boolean

    @Prop({ type: Date, default: null })
    otpRequestTimestamp: Date;

}
export const UserSchema = SchemaFactory.createForClass(User)
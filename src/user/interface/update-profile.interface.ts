import { User } from "../entities/user.entity";
import { BooleanMessage } from "./boolean-message.interface";

export interface UserProfile extends BooleanMessage{
    user : User
}
import { BooleanMessage } from "./boolean-message.interface";

export interface LoginUser extends BooleanMessage{
    token: string
}
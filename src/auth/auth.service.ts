import { Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { InjectModel } from '@nestjs/mongoose';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { User, UserDocument } from '../user/schemas/user.schema';

@Injectable()
export class AuthService {
    constructor(
        @InjectModel(User.name) private userModel: Model<UserDocument>,
        private jwtService: JwtService,
    ) {}

    async register(name: string, email: string, password: string): Promise<User> {
        const hashedPassword = await bcrypt.hash(password, 10);
        console.log("Raj");
        const newUser = new this.userModel({ name, email, passwordHash: hashedPassword });
        return newUser.save();
    }

    async login(email: string, password: string): Promise<{ token: string }> {
        const user = await this.userModel.findOne({ email });

        console.log("login function");
        console.log(user);
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            throw new UnauthorizedException('Invalid credentials');
        }

        const payload = { email: user.email, sub: user._id };

        const token = this.jwtService.sign(payload);

        console.log(token);
        return { token };
    }
}
